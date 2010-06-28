require File.dirname(__FILE__) + '/spec_helper'

RID = "93e78297-57b6-45ec-929c-9da300d724e8"
WMID = "698002155957"

def wminfo(p)
  p["WmLogin_Ticket"] = "TICKET"
  p["WmLogin_UrlID"] = "URL_ID"
  p["WmLogin_Expires"] = "EXPIRES"
  p["WmLogin_AuthType"] = "AUTH_TYPE"
  p["WmLogin_LastAccess"] = "LAST_ACCESS"
  p["WmLogin_Created"] = "CREATED"
  p["WmLogin_WMID"] = "WMID"
  p["WmLogin_UserAddress"] = "USER_IP"
end

describe "WmLogin.authorize" do
  it "should unauthorize when no parameters are passed" do
    request = ActionController::Request.new({'rack.input' => '', 'QUERY_STRING' => "", 'REQUEST_URI' => ""})
    WmLogin.authorize(request, RID, WMID).should == :unauthorized
  end

  it "should authorize when right parameters are passed" do
    request = ActionController::Request.new({'rack.input' => '', 'QUERY_STRING' => "", 'REQUEST_URI' => ""})
    wminfo(request.params)
    
    http = mock("net/http")
    Net::HTTP.should_receive(:new).with('login.wmtransfer.com', 443).and_return(http)
    http.should_receive("use_ssl=").with(true)
    http.should_receive(:post).with("/ws/authorize.xiface", instance_of(String), instance_of(Hash)).
      and_return([nil, "<response retval='0' />"])

    # exception
    Rails.logger.should_not_receive(:error)
    WmLogin.authorize(request, RID, WMID).should == 0
    
    request.session[:wminfo].should_not == nil
  end

  it "should authorize by session" do
    request = ActionController::Request.new({'rack.input' => '', 'QUERY_STRING' => "", 'REQUEST_URI' => ""})
    info = {}
    wminfo(info)
    request.session[:wminfo] = info
    
    http = mock("net/http")
    Net::HTTP.should_receive(:new).with('login.wmtransfer.com', 443).and_return(http)
    http.should_receive("use_ssl=").with(true)
    http.should_receive(:post).with("/ws/authorize.xiface", instance_of(String), instance_of(Hash)).
      and_return([nil, "<response retval='0' />"])

    # exception
    Rails.logger.should_not_receive(:error)
    WmLogin.authorize(request, RID, WMID).should == 0
    
    request.session[:wminfo].should_not == nil
  end
end

describe "ActionWmLogin.wmlogin" do
  it "should redirect to wm site when no params and no session" do
    request = ActionController::Request.new({'rack.input' => '', 'QUERY_STRING' => "", 'REQUEST_URI' => ""})
    c = ApplicationController.new
    c.request = request
    c.should_receive(:redirect_to).with("https://login.wmtransfer.com/GateKeeper.aspx?RID=#{RID}")
    c.wmlogin(:rid => RID, :wmid => WMID)
  end

  it "should login with right parameters" do
    request = ActionController::Request.new({'rack.input' => '', 'QUERY_STRING' => "", 'REQUEST_URI' => ""})
    c = ApplicationController.new
    wminfo(request.params)
    c.request = request
    c.session = request.session

    http = mock("net/http")
    Net::HTTP.should_receive(:new).with('login.wmtransfer.com', 443).and_return(http)
    http.should_receive("use_ssl=").with(true)
    http.should_receive(:post).with("/ws/authorize.xiface", instance_of(String), instance_of(Hash)).
      and_return([nil, "<response retval='0' />"])

    c.logged_in?.should be_false
    c.wmlogin(:rid => RID, :wmid => WMID)
    c.session[:wminfo].should_not == nil
    c.wmuser[:ticket].should == request.params["WmLogin_Ticket"]
    c.logged_in?.should be_true

    # logout
    c.logout
    c.wmuser.should == nil
    c.logged_in?.should be_false
  end
end
