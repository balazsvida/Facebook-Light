require 'yaml'
require 'curl'
require 'md5'
require 'json'

# FacebookLight
module FacebookLight
  
  class Base
      cattr_accessor :tunnel_path, :tunnel_host, :api_key, :secret_key, :canvas_name, :callback_url
      
      class << self
        def init!
          config = YAML::load_file("#{RAILS_ROOT}/config/facebook.yml")
          config = config[ RAILS_ENV == 'development' && config.key?(ENV['USER']) ? ENV['USER'] : RAILS_ENV ]
          
          config.each do |key, value|
            send "#{key}=", value
          end
          
          Client.init!
        end
      end
      
      def logger; RAILS_DEFAULT_LOGGER; end
  end
  
  class Client < Base
    
    attr_accessor :session
    
    def self.init!
      client = Client.new
      props = client.call('admin.getAppProperties', :properties => 'canvas_name, callback_url')
      props.each do |k,v|
        FacebookLight::Base.send("#{k}=", v) unless FacebookLight::Base.send(k)
      end

      if Object.const_defined?("ActionController") && ActionController::Base.asset_host.blank?
        ActionController::Base.asset_host = FacebookLight::Base.callback_url
      end
    end
    
    def call(method, options = {})
      params = {
        'method' => method,
        'api_key' => api_key,
        'format' => 'json',
        'v' => '1.0',
        'call_id' => Time.now.to_f
      }
      params.merge!({'session_key' => session.key}) if session
      params.merge!(options)
      
      curl = Curl::Easy.new(url = url_for(method, append_sig(params)))
      curl.perform
      
      # WORKAROUND: using eval to remove double escapeing
      res = curl.body_str.first == '"' ? eval(curl.body_str) : curl.body_str
      JSON.parse(res)
    end
    
    def append_sig(params)
      params.merge({'sig' => MD5.hexdigest(params.to_a.map{|i| i.join("=")}.sort.push(secret_key).join) })
    end
    
    def url_for(method, params)
      "http://api.facebook.com/restserver.php?#{params.to_param}"
    end
    
  end
  
  module Controller
    def self.included(base)
      base.extend ClassMethods
    end
    
    module ClassMethods
      def acts_as_facebook
        skip_before_filter :verify_authenticity_token
        
        self.send :include, InstanceMethods
        helper_method :fb_url_for
      end
    end
    
    module InstanceMethods
      def facebook
        @facebook ||= Client.new
      end
      
      def facebook_require_login
        unless facebook.session
          if params[:fb_sig_added] == '1'
            facebook.session = Session.new(params[:fb_sig_session_key], params[:fb_sig_user]||params[:fb_sig_canvas_user])
          else
            next_url = "#{request.request_uri}".gsub(/^\/(.*)/, '\1')
            next_url = URI.escape(next_url, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]") )
            render :text =><<-EOS
              <fb:redirect url="http://www.facebook.com/login.php?v=1.0&api_key=#{facebook.api_key}&next=#{next_url}&canvas" />
            EOS
          end
        end
      end
      
      def fb_url_for(options = {})
        case options
        when String
          options.gsub!(/^\/*(.*)/, '/\1')
        when Hash
          options.merge!(:only_path => true)
        end
        
        "/#{facebook.canvas_name}" + url_for(options)
      end
      
    end
  end
  
  class Session < Struct.new(:key, :user); end
  
  class Tunnel < Base
    
    class << self
    
      def remote_uri
        @remote_uri ||= URI.parse("ssh://" + tunnel_host)
      end
      
      def run
        begin
          `ssh -v -p #{remote_uri.port||22} -nNT4 -o "ServerAliveInterval 15" -R *:#{tunnel_path} #{remote_uri.userinfo}@#{remote_uri.host}`
        rescue Interrupt
          nil
        end
      end
      
      def run?
        listened_port = tunnel_path.split(":").first
        `ssh -p #{remote_uri.port||22} #{remote_uri.userinfo}@#{remote_uri.host} netstat -an | 
                egrep "tcp.*:#{listened_port}.*LISTEN" | wc`.to_i > 0
      end
    end
  end
end
