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
      return :unauthorized
    elsif request.params['WmLogin_Ticket'].nil?
      return request.session[:wminfo] ? 0 : :unauthorized
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

    res = WmLogin.authorize(request, rid, wmid)
    # 3 - ticket expired
    if res == :unauthorized || res == 3
      redirect_to "https://login.wmtransfer.com/GateKeeper.aspx?RID=#{rid}"
    elsif res != 0
      raise "AccessDenied"
    else
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
