VMHOST = 172.16.122.2

sync:
	ssh ee122@$(VMHOST) 'sudo killall python'
	rsync -rv . ee122@$(VMHOST):~/proj3

test: sync
	ssh ee122@$(VMHOST) 'cd proj3; ./test.sh'

firewall:
	sudo killall python; cd proj3; sudo ./main.py

# runs the firewall forever even if killed
forever:
	while true; do cd ~/proj3; sudo ./main.py 2>&1; sleep 1; done

watch:
	watchr unittest.watch
