VMHOST = 172.16.122.2

sync:
	rsync -rv . ee122@$(VMHOST):~/proj3

test: sync
	ssh ee122@$(VMHOST) 'cd proj3; ./test.sh'

watch:
	watchr unittest.watch
