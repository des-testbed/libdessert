#!/bin/bash

# important configuration variables, check these if something went wrong
SVN_LIBDESSERT=https://svn.mi.fu-berlin.de/des-testbed/Software/DES-SERT/libdessert/trunk
SVN_IP6=https://svn.mi.fu-berlin.de/des-testbed/Software/DES-SERT/libdessert/trunk/android/netinet
SVN_LIBREGEX=https://svn.mi.fu-berlin.de/des-testbed/Software/DES-SERT/libdessert/trunk/android/libregex/
SVN_LIBPTHREADEX=https://svn.mi.fu-berlin.de/des-testbed/Software/DES-SERT/libdessert/trunk/android/libpthreadex/
SVN_LIBCLIPATCH=https://svn.mi.fu-berlin.de/des-testbed/Software/DES-SERT/libdessert/trunk/android/libcli-patch/

# the android platform (e.g. android-3, android-4, android-5 ...)
ANDROID_PLATFORM=android-3

# android-ndk
NDK_LOCATION=http://dl.google.com/android/ndk
NDK_FILE=android-ndk-r6-linux-x86.tar.bz2
#NDK_FILE=android-ndk-r5b-linux-x86.tar.bz2

# libpcap
LIBPCAP_LOCATION=http://www.tcpdump.org/release/
LIBPCAP_FILE=libpcap-1.1.1.tar.gz

# uthash
UTHASH_LOCATION=http://downloads.sourceforge.net/uthash/
UTHASH_FILE=uthash-1.9.4.tar.bz2

# libcli IMPORTANT: This is a git repository location...you need git to fetch those files.
GIT_LIBCLI=https://github.com/dparrish/libcli



#############################################
# more important variables...DO NOT CHANGE  #
#############################################
INSTALL_DIR=$1
NDK_DIR=${NDK_FILE%"-linux-x86.tar.bz2"}
LIBPCAP_DIR=${LIBPCAP_FILE%".tar.gz"}
UTHASH_DIR=${UTHASH_FILE%".tar.bz2"}

if [[ $INSTALL_DIR != --install_dir\=* ]]
then
	echo "USAGE: ./android.sh --install_dir=..."
	exit 0
fi

INSTALL_DIR=${INSTALL_DIR:14}
if [[ ${INSTALL_DIR:0:1} != "/" ]]
then
	echo "--install_dir=... expects an absolute path!"
	exit 0
fi

type -P git &>/dev/null || echo "You need to have \"git\" installed, but it is not.  Aborting."

export DESSERT_LIB=$INSTALL_DIR"/dessert-lib"

lchr=`expr substr $NDK_LOCATION ${#NDK_LOCATION} 1`
if [ ! "$lchr" == "/" ]
then
	NDK_LOCATION=$NDK_LOCATION"/"
fi

lchr=`expr substr $LIBPCAP_LOCATION ${#LIBPCAP_LOCATION} 1`
if [ ! "$lchr" == "/" ]
then
	LIBPCAP_LOCATION=$LIBPCAP_LOCATION"/"
fi

lchr=`expr substr $UTHASH_LOCATION ${#UTHASH_LOCATION} 1`
if [ ! "$lchr" == "/" ]
then
	UTHASH_LOCATION=$UTHASH_LOCATION"/"
fi


ANDROID_TOOLCHAIN=$INSTALL_DIR"/android-toolchain"
if [ ! -d "$INSTALL_DIR" ]
then
	echo "Installation directory does not exist. Creating it..."
	mkdir -p $INSTALL_DIR
fi

# switch to installation directory
cd $INSTALL_DIR

# cleanup old files
echo "Cleaning up old files (from previous installations)..."
rm -rf libdessert bin libcli $NDK_FILE $UTHASH_FILE $LIBPCAP_FILE

# Create necessary subdirectories
echo "Creating subdirectories..."
mkdir bin
mkdir -p dessert-lib/{include,lib}

# fetch ndk from configured location
echo "Downloading NDK..."
wget -nc -q $NDK_LOCATION$NDK_FILE
if [ ! -e "$NDK_FILE" ]
then
	echo "Failed to download Android NDK. Aborting!"
	exit 0
fi

# fetch needed files from repository
echo "Checking out current libdessert from repository..."
svn co -q $SVN_LIBDESSERT
if [ -d "trunk" ]
then
	echo "Renaming trunk/ to libdessert/..."
	mv trunk libdessert
else
	echo "Something went wrong while fetching libdessert from the repository...aborting."
	exit 0
fi

# install android-ndk and toolchain
echo "Installing android-ndk..."
tar xvjf $NDK_FILE &> /dev/null
cd $NDK_DIR"/build/tools"
export ANDROID_NDK_ROOT=$INSTALL_DIR"/"$NDK_DIR
export ANDROID_NDK_HOME=$INSTALL_DIR"/"$NDK_DIR
./make-standalone-toolchain.sh --ndk-dir=$INSTALL_DIR"/"$NDK_DIR --install-dir=$ANDROID_TOOLCHAIN
echo "Setting ANDROID_TOOLCHAIN..."
export ANDROID_TOOLCHAIN=$ANDROID_TOOLCHAIN
echo "Android Toolchain dir set to $ANDROID_TOOLCHAIN"
if [ ! -d "$ANDROID_TOOLCHAIN" ]
then
	echo "Failed to install android toolchain. Aborting"
	exit 0
fi
cd $INSTALL_DIR

# copy android-gcc and android-strip to bin directory
echo "Copying android-gcc wrapper to bin..."
cp libdessert/android/android-* bin

# add bin directory to path
echo "Adding bin directory to path..."
export PATH=$INSTALL_DIR/bin:${PATH}

# installing uthash
echo "Installing uthash headers..."
wget -nc -q $UTHASH_LOCATION$UTHASH_FILE
if [ ! -e "$UTHASH_FILE" ]
then
	echo "Failed to download UTHASH. Aborting!"
	exit 0
fi
tar xvjf $UTHASH_FILE &> /dev/null
cd $UTHASH_DIR"/src"
cp *.h $INSTALL_DIR"/dessert-lib/include"
cd $INSTALL_DIR

# installing netinet headers
echo "Installing netinet/ip6.h..."
cd dessert-lib/include
svn co $SVN_IP6
if [ ! -d "netinet" ]
then
	echo "Failed to downloat netinet/ip6.h. Aborting."
	exit 0
fi
cd $INSTALL_DIR

# setting android-gcc as standard compiler
export CC="android-gcc"

# installing libregex
echo "Installing libregex..."
svn co $SVN_LIBREGEX
if [ ! -d "libregex" ]
then
	echo "Failed to download libregex. Aborting."
	exit 0
fi
cd libregex 
make CC="android-gcc" DESTDIR="$INSTALL_DIR" PREFIX="/dessert-lib" clean all install &> build.log
cd $INSTALL_DIR
if [ ! -e "dessert-lib/lib/libregex.a" ]
then
	echo "Failed to built libregex. See \"dessert-lib/libregex/build.log\"!"
	exit 0
fi

# installing libpthreadex
echo "Installing libpthreadex..."
svn co $SVN_LIBPTHREADEX
if [ ! -d "libpthreadex" ]
then
	echo "Failed to download libpthreadex. Aborting!"
	exit 0
fi
cd libpthreadex
make CC="android-gcc" DESTDIR="$INSTALL_DIR" PREFIX="/dessert-lib" clean all install &> build.log
cd $INSTALL_DIR
if [ ! -e "dessert-lib/lib/libpthreadex.a" ]
then 
	echo "Failed to build libpthreadex. See \"libpthreadex/build.log\""
	exit 0
fi

# installing libcli
echo "Installing libcli..."
git clone $GIT_LIBCLI
if [ ! -d "libcli" ]
then
	echo "Failed to create git repository for libcli. Aborting."
	exit 0
fi
echo "Patching libcli..."
svn co $SVN_LIBCLIPATCH
cp libcli-patch/libcli.patch libcli
cd libcli
patch < libcli.patch
make CC="android-gcc" CFLAGS="-I$INSTALL_DIR/dessert-lib/include -I. -DSTDC_HEADERS" LDFLAGS="-shared $INSTALL_DIR/dessert-lib/lib/libregex.a -Wl,-soname,libcli.so" LIBS="" DESTDIR="$INSTALL_DIR" PREFIX="/dessert-lib" clean libcli.so install &> build.log
cd $INSTALL_DIR
if [ ! -e "dessert-lib/lib/libcli.so" ]
then
	echo "Failed to build libcli. See \"libcli/build.log\""
	exit 0
fi

# installing libpcap
echo "Installing libpcap..."
wget -nc -q $LIBPCAP_LOCATION$LIBPCAP_FILE
if [ ! -e "$LIBPCAP_FILE" ]
then 
	echo "Failed to download libpcap. Aborting!"
	exit 0
fi
tar xvzf $LIBPCAP_FILE &> /dev/null
cd $LIBPCAP_DIR
./configure CFLAGS="-Dlinux" --prefix=$INSTALL_DIR"/dessert-lib" --host=arm-none-linux --with-pcap=linux ac_cv_linux_vers=2 ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes
make &> build.log
make install
cd $INSTALL_DIR
if [ ! -e "dessert-lib/lib/libpcap.a" ]
then
	echo "Failed to build libpcap. See \"libpcap/build.log\""
	exit 0
fi

# building libdessert
echo "Building libdessert..."
cd libdessert
sh autogen.sh
./configure CFLAGS="-I$INSTALL_DIR/dessert-lib/include -I$ANDROID_NDK_HOME/platforms/$ANDROID_PLATFORM/arch-arm/usr/include -D__linux__" LDFLAGS="-L$INSTALL_DIR/dessert-lib/lib -L$ANDROID_NDK_HOME/platforms/$ANDROID_PLATFORM/arch-arm/usr/lib" --prefix=$INSTALL_DIR"/dessert-lib/" --host=arm-none-linux --without-net-snmp --enable-android-build ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes
# setting the CPPFLAGS fixes a flaw in the configure script, where always the standard include "/usr/include" is appended to the compiler flags
make CPPFLAGS="" &> build.log
make install
cd $INSTALL_DIR
if [ ! -e "dessert-lib/lib/libdessert.a" ]
then
	echo "Failed to build libdessert. See \"libdessert/build.log\"."
	exit 0
fi

# cleanup
echo "Cleaning up..."
rm *.tar.gz
rm *.bz2
rm -rf libcli libcli-patch libdessert libpcap-1.1.1 libpthreadex libregex uthash-1.9.3

# Building archive
echo "Building archive..."
tar cvzf libdessert_android.tar.gz dessert-lib &> /dev/null

echo ""
echo "IMPORTANT: Check if any errors occured! If yes, you first need to manually fix them and restart this script."
echo ""
echo "PRESS A KEY TO CONTINUE..."
read -n 1 -s
echo "The library has been tar'ed to the file libdessert_android.tar.gz."
echo "=================================================================="
echo "As last step you have to set the following environment variables:"
echo "  export ANDROID_TOOLCHAIN=$ANDROID_TOOLCHAIN"
echo "  export DESSERT_LIB=$INSTALL_DIR/dessert-lib"
echo "  export ANDROID_NDK_HOME=$INSTALL_DIR/$NDK_DIR"
echo "  export PATH=\$PATH:$INSTALL_DIR/bin"
echo "=================================================================="
echo "You can now do: make android from any dessert daemon source dir!"

