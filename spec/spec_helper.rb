# ../vendor/plugin/YOUR_PLUGIN/spec/spec_helper.rb
begin
  # load your main app spec_helper
  require File.dirname(__FILE__) + '/../../../../spec/spec_helper'
rescue LoadError
  puts "You need to install rspec in your base app"
  exit
end
