### Python deploy script
Midnight Commander is a very great tool (`sudo apt install mc`), but sometimes you need to upload files 
in automatic mode. As example you use webpack on some development server.
In that case it will be a lot faster if you sources might be deployed automatically
and then process there.
 
This tool makes all work. Script makes a cache in your home directory to determine which files
was been modified in order not to do excessive work.

You need to specify a host, user,
password or ssh keys and path mappings, excluded directories and files and so on.

Note, script tracks global keyboard. Default shortcuts are these (you can override them):
+ `ctrl+alt+shift+x` - upload all
+ `ctrl+alt+shift+z` - clear **all** cache (this means all files will be re-uploaded in next upload)

See config examples in deploy.config
