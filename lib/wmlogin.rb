#
# Wmlogin
#
# API: https://login.wmtransfer.com/Help.aspx?AK=default
#

require 'rexml/document'
require 'net/http'
require 'net/https'

module WmLogin
  #
  # return status code https://login.wmtransfer.com/Help.aspx?AK=ws/result
  #
  def self.authorize(request, rid, wmid)
    if request.params['WmLogin_Ticket'].nil? && request.session[:wminfo].nil?
      info = nil
    elsif request.params['WmLogin_Ticket'].nil?
      info = request.session[:wminfo]
    else
      info = {
        :ticket => request.params["WmLogin_Ticket"],
        :url_id => request.params["WmLogin_UrlID"],
        :expires => request.params["WmLogin_Expires"],
        :auth_type => request.params["WmLogin_AuthType"],
        :last_access => request.params["WmLogin_LastAccess"],
        :created => request.params["WmLogin_Created"],
        :wmid => request.params["WmLogin_WMID"],
        :user_ip => request.params["WmLogin_UserAddress"],
      }
    end
    return :unauthorized unless info

    http = Net::HTTP.new('login.wmtransfer.com', 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    #http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    #http.cert = OpenSSL::X509::Certificate.new(File.read(File.dirname(__FILE__) + "/wmtransfer.pem"))
    #http.ca_file = File.dirname(__FILE__) + "/wmtransfer.pem"
    path = '/ws/authorize.xiface'

    data = ("<request><siteHolder>%s</siteHolder><user>%s</user><ticket>%s</ticket>" +
            "<urlId>%s</urlId><authType>%s</authType><userAddress>%s</userAddress></request>") %
           [wmid, info[:wmid], info[:ticket], info[:url_id], info[:auth_type], info[:user_ip]]
    headers = {
      'Content-Type' => 'application/x-www-form-urlencoded'
    }
    begin
      resp, data = http.post(path, data, headers)
      doc = REXML::Document.new(data)
      res = doc.elements["response"].attributes["retval"].to_i
      request.session[:wminfo] = info if res == 0
      return res
    rescue Exception => e
      # TODO: log this error
      Rails.logger.error("WmLogin authorize exception: " + e.inspect)
      # internal error
      return -1
    end
  end

  #
  # Verify ticket
  # return status code https://login.wmtransfer.com/Help.aspx?AK=ws/result
  #
  def self.verify(request, ticket, wmid, password)
    http = Net::HTTP.new('login.wmtransfer.com', 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    path = '/ws/ProtectedSecurity.asmx'
    data = "<?xml version='1.0' encoding='utf-8'?>" +
"<soap:Envelope xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xsd='http://www.w3.org/2001/XMLSchema' xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>" +
"  <soap:Body><GetTicketInfo xmlns='http://WmLogin.webmoney.ru/'>" +
"      <siteHolderWmId>#{wmid}</siteHolderWmId>" +
"      <password>#{password}</password>" +
"      <ticket>#{ticket}</ticket>" +
"  </GetTicketInfo></soap:Body>" +
"</soap:Envelope>"
    headers = {
      'Content-Type' => 'text/xml; charset=utf-8',
      'SOAPAction' => '"http://WmLogin.webmoney.ru/GetTicketInfo"'
    }
    begin
      resp, data = http.post(path, data, headers)
      doc = REXML::Document.new(data)
      d = doc[1][0][0]
      res = d.elements['GetTicketInfoResult'].text.to_i
      if res == 0
        info = {
          :ticket => ticket,
          :url_id => d.elements["urlId"].text,
          :expires => d.elements["expires"].text,
          :auth_type => d.elements["authType"].text,
          :last_access => d.elements["lastAccess"].text,
          :created => d.elements["created"].text,
          :wmid => d.elements['wmId'].text,
          :user_ip => d.elements["userAddress"].text,
        }
        request.session[:wminfo] = info
      end
      return res
    rescue Exception => e
      # TODO: log this error
      Rails.logger.error("WmLogin authorize exception: " + e.inspect)
      # internal error
      return -1
    end
  end
end

module ActionWmLoginClass
  def wmlogin(*args)
    self.before_filter(*args) do |c|
      c.wmlogin(*args)
    end
  end
end

module ActionWmLogin
  def wmlogin(*args)
    wmid = args[0][:wmid]
    rid = args[0][:rid]
    password = args[0][:password]
    check_ip = args[0][:check_ip]
    check_ip = RAILS_ENV == "production" if check_ip.nil?

    res = WmLogin.authorize(request, rid, wmid)
    if res != 0 && request.params[:ticket] && request.params[:ticket] =~ /^[0-9a-zA-Z\!\-\$\#]{40,60}$/ && password
      res = WmLogin.verify(request, request.params[:ticket], wmid, password)
    end

    # 3 - ticket expired
    if res == :unauthorized || res == 3
      redirect_to "https://login.wmtransfer.com/GateKeeper.aspx?RID=#{rid}"
    elsif res != 0
      raise "AccessDenied"
    else
      if check_ip && session[:wminfo][:user_ip] != request.ip
        raise "AccessDenied"
      end
      @wmuser = session[:wminfo]
    end
  end

  def wmuser
    @wmuser
  end

  def logged_in?
    !@wmuser.nil?
  end

  def logout
    # webmoney.login service does not support this function
    session[:wminfo] = nil
    @wmuser = nil
  end
end

ActionController::Base.send(:extend, ActionWmLoginClass)
ActionController::Base.send(:include, ActionWmLogin)
