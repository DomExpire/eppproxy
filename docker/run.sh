#!/bin/sh

conf=/etc/exim4/update-exim4.conf.conf

echo "# exim config" > ${conf}
echo "dc_eximconfig_configtype='internet'" >> ${conf}
echo "dc_other_hostnames='${MAILNAME:-eppproxy.fr}'" >> ${conf}
echo "dc_local_interfaces=''" >> ${conf}
echo "dc_readhost=''" >> ${conf}
echo "dc_relay_domains=''" >> ${conf}
echo "dc_minimaldns='false'" >> ${conf}
echo "dc_relay_nets=''" >> ${conf}
echo "dc_smarthost=''" >> ${conf}
echo "CFILEMODE='644'" >> ${conf}
echo "dc_use_split_config='false'" >> ${conf}
echo "dc_hide_mailname='true'" >> ${conf}
echo "dc_mailname_in_oh='true'" >> ${conf}
echo "dc_localdelivery='mail_spool'" >> ${conf}
echo "MAIN_HARDCODE_PRIMARY_HOSTNAME=${MAILNAME:-eppproxy.fr}" >> ${conf}

echo ${MAILNAME:-eppproxy.fr} > /etc/mailname

update-exim4.conf
/usr/sbin/exim4 -bdf -q30m &
./ctl start
tail -f /dev/null