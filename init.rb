# Include hook code here

FacebookLight::Base.init!

ActionController::Base.send :include, FacebookLight::Controller
