# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it.
Vagrant.configure(2) do |config|
  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "ubuntu/trusty64"

  # Forward our (new) SNFS port 2048 to the host (NFS is 2049...)
  # config.vm.network "forwarded_port", guest: 2048, host: 2048

  # Add another path to the current directory at ~lab3
  config.vm.synced_folder ".", "/home/vagrant/lab3"

  # Give the virtual machine a little OOMPH
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 4
    v.customize ["guestproperty", "set", :id,
        "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000]
    v.customize ['guestproperty', 'set', :id,
        "/VirtualBox/GuestAdd/VBoxService/--timesync-interval", 1000]
  end

  # Install pkg-config and the fuse headers
  config.vm.provision "shell", inline: <<-SHELL
    sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    sudo apt-get update
    sudo apt-get install -y pkg-config
    sudo apt-get install -y libbsd-dev
    sudo apt-get install -y libfuse-dev
    sudo apt-get install -y zlib1g-dev
    sudo apt-get install -y libbz2-dev
    sudo apt-get install -y g++-4.9
    sudo apt-get install -y git
    sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.9 40
    
  SHELL
end
