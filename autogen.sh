#!/bin/sh

# ugly hack to get libtools major version
LIBTOOL_MAJOR_VERSION=`libtool --version | head -n 1 | cut -d " " -f 4 | cut -c1`

M4_PATH="m4"

M4_FILES="libtool.m4 \
          ltoptions.m4 \
          ltsugar.m4 \
          ltversion.m4 \
          lt~obsolete.m4 \
         "

if test ${LIBTOOL_MAJOR_VERSION} -lt 2; then
   for i in ${M4_FILES}
   do
      rm ${M4_PATH}/${i}
   done
fi

autoreconf --force --install -I m4
