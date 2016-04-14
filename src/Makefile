TARGET=auth_ldap.so
CC=gcc48
INCLUDES=`mysql_config --cflags` -fPIC -DMYSQL_DYNAMIC_PLUGIN
CFLAGS=
CPPFLAGS=

.PHONY: all clean api-test

all: api-test
	@echo "  == API Test: PASSED =="
	@echo "  == openLDAP API seems to be OK! =="
	$(MAKE) $(TARGET)

$(TARGET): auth_ldap.o
	$(CC) -shared -lconfig -o $@ $<

auth_ldap.o: auth_ldap.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f auth_ldap.o auth_ldap.so

install: $(TARGET)
	install -m 0644 $(TARGET) /usr/local/lib/mysql/plugin

api-test:
	$(MAKE) auth_ldap.so CFLAGS+='-DAUTH_LDAP_TEST_API'
	$(MAKE) clean
