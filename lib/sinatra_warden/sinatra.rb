require 'sinatra/base'
require File.join(File.dirname(__FILE__), 'helpers')

module Sinatra
  module Warden
    def self.registered(app)
      app.helpers Warden::Helpers

      # Enable Sessions
      app.set :sessions, true

      app.set :auth_failure_path, '/'
      app.set :auth_success_path, '/'
      # Setting this to true will store last request URL
      # into a user's session so that to redirect back to it
      # upon successful authentication
      app.set :auth_use_referrer, false

      app.set :auth_error_message,   "Could not log you in."
      app.set :auth_success_message, "You have logged in successfully."
      app.set :auth_template_renderer, :haml
      app.set :auth_login_template, :login

      # OAuth Specific Settings
      app.set :auth_use_oauth, false

      app.post '/unauthenticated/?' do
        status 401
        warden.custom_failure! if warden.config.failure_app == self.class
        env['x-rack.flash'][:error] = options.auth_error_message if defined?(Rack::Flash)
        self.send(options.auth_template_renderer, options.auth_login_template)
      end

      app.get '/login/?' do
        if options.auth_use_oauth && !@auth_oauth_request_token.nil?
          session[:request_token] = @auth_oauth_request_token.token
          session[:request_token_secret] = @auth_oauth_request_token.secret
          redirect @auth_oauth_request_token.authorize_url
        else
          self.send(options.auth_template_renderer, options.auth_login_template)
        end
      end

      app.get '/oauth_callback/?' do
        if options.auth_use_oauth
          authenticate
          env['x-rack.flash'][:success] = options.auth_success_message if defined?(Rack::Flash)
          redirect options.auth_success_path
        else
          redirect options.auth_failure_path
        end
      end

      app.post '/login/?' do
        authenticate
        env['x-rack.flash'][:success] = options.auth_success_message if defined?(Rack::Flash)
        redirect options.auth_use_referrer && session[:return_to] ? session.delete(:return_to) : 
                 options.auth_success_path
      end

      app.get '/logout/?' do
        authorize!
        logout
        env['x-rack.flash'][:success] = options.auth_success_message if defined?(Rack::Flash)
        redirect options.auth_success_path
      end
    end
  end # Warden

  register Warden
end
