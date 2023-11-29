# godot-mariadb
A Godot engine module for MariaDB that is a MIT licensed connector separate from the Maria/MySQL GPL connectors.  
This module will compile on Linux, Windows, probably Mac. However, it is extremely suggested that you use this on Linux, there have been reports of unconfirmed Windows issues.  
  
Originally created for Godot 3.4 and currently works on 3.5.3 and 4.1.3, the main branch will stay current with Godot stable releases for Godot 3.x checkout the relevant release or branch.  
  
**To compile on to a stable version you will need to clone the Godot repo...**  
git clone https://github.com/godotengine/godot.git  

**List the stable releases with...**  
git tag  
**-or- find a major release with, eg 4.x-stable**  
git tag -l '4.\*stable'  

**Checkout the stable release you want, in this case 4.0.3-stable...**  
git checkout 4.0.3-stable  

**Change to the modules directory...**  
cd modules  

**Clone this repo as a git submodule...**  
git submodule add https://github.com/sigrudds1/godot-mariadb.git mariadb  

**Change to the just created mariadb directory...**  
cd mariadb  

**Find the relevant release to the Godot version...**  
git tag  

**Checkout/switch to the relevant release, e.g. match Godot 4.0.4-stable, git version 2.23+**  
git checkout v4.0.3

**Alternately you can use a branch rather than release...**  
git branch -v -a

**Checkout the branch, e.g. 4.x, git version 2.23+**  
git checkout 4.x

**Change back to the main Godot directory...**  
cd ../..  

**Compile Godot, e.g. editor version Linux 64 bit, see the Godot manual for compilation instructions for other releases and export templates, make sure you're on the correct manual version.**  
Godot 4.x  
scons -j$(nproc) platform=linuxbsd target=editor arch=x86_64  
Godot 3.x  
scons -j$(nproc) platform=x11  
  
I will have a tutorial up on https://vikingtinkerer.com, once I feel it has been tested enough to be considered stable.  
[Buy Me A Coffee](https://buymeacoffee.com/VikingTinkerer)  
  or  
[Buy Me A Ko-Fi](https://ko-fi.com/vikingtinkerer)

