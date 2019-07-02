CC                  = gcc
CCC                 = g++

INCLUDE_DIRS        = -I . \
                      -I ../include

LIB_LOOKUP_DIRS     = -L ../lib

LIBS                = -lplist \
                      -lcryptopp \
                      -lssl \
                      -lcrypto

CCFLAGS             = -pthread
CCCFLAGS            = -pthread -std=c++0x -DDSRP_DANGEROUS_TESTING -DATV -fpermissive

OBJ_CPPATV          = main.o \
                      simpleHttpClient.o

OBJ-DSRP            = dsrp/conversionexception.o \
                      dsrp/conversion.o \
                      dsrp/srpclient.o \
                      dsrp/user.o \
                      dsrp/ng.o \
                      dsrp/dsrpexception.o \
                      dsrp/lookupinterface.o \
                      dsrp/hashinterface.o \
                      dsrp/mathinterface.o \
                      dsrp/randominterface.o \
                      dsrp/srpverificator.o \
                      dsrp/srpserver.o \
                      dsrp/usernotfoundexception.o \
                      dsrp/srpclientauthenticator.o \
                      dsrp/memorylookup.o

OBJ-OSSL            = ossl/osslmd5.o \
                      ossl/osslsha1.o \
                      ossl/osslsha256.o \
                      ossl/osslsha512.o \
                      ossl/osslrandom.o \
                      ossl/osslmathimpl.o \
                      ossl/osslconversion.o

TARGET              = cppatv

all: main dsrp ossl dsrp-app

main: $(OBJ_CPPATV) $(OBJ-DSRP) $(OBJ-OSSL)
	$(CCC) $(OBJ_CPPATV) $(OBJ-DSRP) $(OBJ-OSSL) $(LIB_LOOKUP_DIRS) $(LIBS) $(CCCFLAGS) -o $(TARGET)

#build the object files for dsrp
dsrp: $(OBJ-DSRP)

#to build ossl we first need to have build dsrp
ossl: dsrp $(OBJ-OSSL)

#build the dsrp-app for testing
dsrp-app: app-srp

app-srp: app-srp-server-test app-srp-client-test app-srp-create-user app-srp-benchmark app-srp-rfctest app-srp-qtest

app-srp-server-test: dsrp ossl apps/server_test.o
	$(CCC) apps/server_test.o $(OBJ-DSRP) $(OBJ-OSSL) -o apps/server_test $(LIB_LOOKUP_DIRS) $(LIBS)

app-srp-client-test: dsrp ossl apps/client_test.o
	$(CCC) apps/client_test.o $(OBJ-DSRP) $(OBJ-OSSL) -o apps/client_test $(LIB_LOOKUP_DIRS) $(LIBS)

app-srp-create-user: dsrp ossl apps/create_user.o
	$(CCC) apps/create_user.o $(OBJ-DSRP) $(OBJ-OSSL) -o apps/create_user $(LIB_LOOKUP_DIRS) $(LIBS)

app-srp-benchmark: dsrp ossl apps/benchmark.o
	$(CCC) apps/benchmark.o $(OBJ-DSRP) $(OBJ-OSSL) -o apps/benchmark $(LIB_LOOKUP_DIRS) $(LIBS)

app-srp-rfctest: dsrp ossl apps/rfc_test.o
	$(CCC) apps/rfc_test.o $(OBJ-DSRP) $(OBJ-OSSL) -o apps/rfc_test $(LIB_LOOKUP_DIRS) $(LIBS)

app-srp-qtest: dsrp ossl apps/qtest.o
	$(CCC) apps/qtest.o $(OBJ-DSRP) $(OBJ-OSSL) -o apps/qtest $(LIB_LOOKUP_DIRS) $(LIBS)

#tells how to make an *.o object file from an *.c file
%.o: %.c
	$(CC) -c $(INCLUDE_DIRS) $< $(CCFLAGS) -o $@

#tells how to make an *.o object file from an *.cpp file
%.o: %.cpp
	$(CCC) -c $(INCLUDE_DIRS) $< $(CCCFLAGS) -o $@

clean:
	rm -f *.o
	rm -f dsrp/*.o
	rm -f ossl/*.o
	rm -f apps/server_test
	rm -f apps/client_test
	rm -f apps/create_user
	rm -f apps/benchmark
	rm -f apps/qtest
	rm -f apps/rfc_test
	rm -f apps/*.o
	rm -f $(TARGET)
