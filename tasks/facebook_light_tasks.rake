desc "Explaining what the task does"
task :facebook_light => :environment do
  puts FacebookLight::Tunnel.run
end
