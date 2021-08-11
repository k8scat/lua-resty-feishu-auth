ROCKSPEC =
LUAROCKS_API_KEY =

luarocks-upload:
	luarocks upload $(ROCKSPEC) --api-key=$(LUAROCKS_API_KEY)
