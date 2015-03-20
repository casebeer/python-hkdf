# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  config.vm.provision "shell", inline: <<-SHELL
     #!/bin/bash

     function aptq {
         sudo aptitude install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" $@
     }

     sudo add-apt-repository ppa:fkrull/deadsnakes

	 sudo aptitude update

     aptq python2.6
     aptq python2.7
     aptq python3.1
     aptq python3.2
     aptq python3.3
     aptq python3.4
     aptq python-tox
     aptq git

     ln -snf /vagrant ~vagrant/devl
  SHELL
end
