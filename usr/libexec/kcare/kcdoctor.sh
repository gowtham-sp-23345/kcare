#!/bin/bash

DOCTOR_VERSION='1.0-8'

LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
LANGUAGE=en_US.UTF-8
DEST=/root/cl-report

DOCTOR_HOST=${1:-https://patches.kernelcare.com}
UPLOAD_URL="${DOCTOR_HOST}/doctor/upload"
SHOWIP_URL="${DOCTOR_HOST}/myip"
CAT=`command -v cat`
UNAME=`command -v uname`
CP="Unknown"
SERVER_ID=
main_ip='NA'

cleanup() {
  rm -f $DEST $DEST.wget
}

test_curl() {
  command -v curl 2>&1 >/dev/null
  return $?
}

test_wget() {
  command -v wget 2>&1 >/dev/null
  if [ 0 -eq $? ]; then
    if [ -x `command -v wget` ]; then
      return 0
    fi
  fi
  return 1
}

curl_upload() {
  curl --fail -s -H "serverid: $SERVER_ID" -F reportfile=@"$DEST" $UPLOAD_URL
  return $?
}

wget_upload() {
  echo -e "--FILEUPLOAD\r\n" > $DEST.wget
  echo -e "--FILEUPLOAD\r\n" > $DEST.wget
  echo -e "Content-Disposition: form-data; name=\"reportfile\"; filename=\"$DEST\"\r\n" >> $DEST.wget
  echo -e "Content-Type: application/octet-stream\r\n" >> $DEST.wget
  echo -e "Media Type: application/octet-stream\r\n\r\n" >> $DEST.wget
  cat $DEST >> $DEST.wget
  echo -e "--FILEUPLOAD--\r\n" >> $DEST.wget
  wget -O - -qq -t 1 --header="serverid: $SERVER_ID" --header="Content-type: multipart/form-data; boundary=FILEUPLOAD" --post-file $DEST.wget $UPLOAD_URL
  return $?
}

get_server_id() {
  if [ -f /etc/sysconfig/kcare/systemid ]; then
    source /etc/sysconfig/kcare/systemid
    SERVER_ID="$server_id"
  else
    SERVER_ID="${main_ip//./_}"
  fi
}

init_main_ip() {
   if test_curl
   then
      main_ip=`curl -4 -s -L ${SHOWIP_URL}` 2>/dev/null
   else
      main_ip=`wget -qq --inet4-only -O - ${SHOWIP_URL}` 2>/dev/null
   fi
}

get_main_ip() {
  sep "Main IP"
  echo "$main_ip" >> $DEST
  echo >>$DEST
}

upload() {
  if test_curl
  then
    curl_upload
  else
    wget_upload
  fi
  return $?
}

mecho(){
  echo $1 >> $DEST
}

start(){
  if ! test_wget; then
    if ! test_curl; then
      echo "Cannot find wget or curl"
    fi
    #echo "Using curl"
  fi
  echo "------ CL INFO ---" > $DEST
}

sep(){
  echo "------ $1 ---" >> $DEST
}

run(){
  sep "$1"
  sh -c "$1" >> $DEST 2>&1
}

dump() {
  sep "cat $1"
  $CAT $1  >> $DEST 2>&1
}

detect_cp() {
  CP_VERSION="Unknown"
  SOFTACULOUS=0
  if [ -d "/usr/local/psa/admin/" ]; then
    CP="Plesk"
    CP_VERSION=`cat /usr/local/psa/version`
    if [ -e "/usr/local/softaculous" ]; then SOFTACULOUS=1; fi
  fi
  if [ -d "/usr/local/cpanel/whostmgr/docroot/" ]; then
    CP="cPanel"
    CP_VERSION=`/usr/local/cpanel/cpanel -V`
    if [ -e "/usr/local/cpanel/whostmgr/cgi/softaculous" ]; then SOFTACULOUS=1; fi
  fi
  if [ -d "/usr/local/interworx/" ]; then
    CP="InterWorx"
    CP_VERSION=`cat /usr/local/interworx/iworx.ini|grep version`
    if [ -e "/usr/local/softaculous" ]; then SOFTACULOUS=1; fi
  fi
  if [ -d "/usr/local/ispmgr/" ]; then
    CP="ISPmanager"
    CP_VERSION=`/usr/local/ispmgr/bin/ispmgr -v`
    if [ -e "/usr/local/softaculous" ]; then SOFTACULOUS=1; fi
  fi
  if [ -d "/usr/local/directadmin/plugins/" ]; then
    CP="DirectAdmin"
    CP_VERSION=`/usr/local/directadmin/custombuild/build versions|sed -n 2p|cut -d":" -f2`
    if [ -e "/usr/local/directadmin/plugins/softaculous" ]; then SOFTACULOUS=1; fi
  fi
  if [ -d "/usr/local/hostingcontroller/" ]; then
    CP="Hosting Controller"
    if [ -e "/usr/local/softaculous" ]; then SOFTACULOUS=1; fi
  fi
  if [ -d "/hsphere/shared" ]; then
    CP="H-Sphere"
  fi
  sep "Control Panel"
  mecho "CP: $CP"
  mecho "VERSION: $CP_VERSION"
  mecho "SOFTACULOUS: $SOFTACULOUS"
}

get_packages() {
  sep 'rpm -q -a --queryformat="%{N}|%{V}-%{R}|%{arch}\n"'
  if [ -f '/usr/bin/rpm' ]; then
    sh -c 'rpm -q -a --queryformat="%{N}|%{V}-%{R}|%{arch}|%{INSTALLTIME:date}\n"' >> $DEST 2>&1
  fi
  if [ -f '/usr/bin/dpkg' ]; then
    sh -c "/usr/bin/dpkg-query -W -f '\${binary:Package}|\${Version}|\${Architecture}\\n'" >> $DEST 2>&1
    sh -c "grep ' install ' /var/log/dpkg.log" >> $DEST 2>&1
  fi
}


dump_kmsgs() {
  find "${CR_DIR}" -name "kmsg*log" | while read dump_file; do dump "${dump_file}"; done
}

dump_crash_logs() {
  find "${CR_DIR}" -name "[[:digit:]]*\.log" | while read dump_file; do dump "${dump_file}"; done
}

get_sysfs_info_detail() {
  files=$(find /sys -type f -name "$1" \
               ! -path "/sys/kernel/debug/tracing/events*" \
               ! -path "/sys/kernel/tracing/events*" \
               ! -path "/sys/devices*")
  for file in $files; do
    echo "cat $file" >> $DEST 2>&1
    cat "$file" >> $DEST 2>&1
    echo >> $DEST 2>&1
  done
}

get_sysfs_info() {
  sep 'sysfs config'
  get_sysfs_info_detail "enable*"
  get_sysfs_info_detail "nr_*"
  get_sysfs_info_detail "max_*"
  get_sysfs_info_detail "*cnt*"
}

start
echo -n "Generating report..."

run "echo doctor version: ${DOCTOR_VERSION}"

run "tail -n10000 /var/log/syslog"
run dmesg
run "tail -n10000 /var/log/messages"
run "ls -lR /var/cache/kcare/"
dump "/etc/sysconfig/kcare/kcare.conf"
run "/usr/libexec/kcare/virt-what"

init_main_ip
get_main_ip
get_server_id
run "echo server_id: ${SERVER_ID}"
run "echo kernel_id: $(sha1sum /proc/version)"
run "date"
run "$CAT /proc/cpuinfo"
run "$UNAME -a"
run "$UNAME -r"
run "$UNAME -m"
run "$UNAME -p"
run "$UNAME -o"
dump "/etc/redhat-release"
dump "/etc/debian_version"
dump "/etc/os-release"
dump "/etc/issue"
dump "/etc/sysconfig/kernel"
dump "/proc/uptime"
dump "/proc/loadavg"
dump "/proc/vmstat"
dump "/proc/devices"
dump "/proc/diskstats"
dump "/proc/cmdline"
dump "/proc/mdstat"
dump "/proc/meminfo"
dump "/proc/swaps"
dump "/proc/filesystems"
dump "/proc/mounts"
dump "/proc/interrupts"
dump "/boot/grub/grub.conf"
dump "/proc/version"
dump "/proc/modules"
run "grep DEFAULT /etc/default/grub"
run "grep vmlinuz /boot/grub2/grub.cfg| sed 's/root=.*//'"
dump "/boot/grub2/grub.cfg"
dump "/proc/zoneinfo"
run "ls /etc/grub.conf /boot/grub/grub.conf /boot/grub/menu.lst"
run "ls -l /boot"
run "printenv"
run "grep Port /etc/ssh/sshd_config"
run "dmidecode"
run "ipcs -m|sed -e s/-/=/g"
run "sysctl -a"
dump "/etc/sysctl.conf"
get_packages
run 'lspci -vv'
run "dpkg -l"
run "grep -rE '^(deb|URIs)' /etc/apt/sources.list*"
run "echo /etc/yum.repos.d/*"
dump "/etc/yum.conf"
run "yum repolist"
run "tail -n10000 /var/log/libcare/*.log"
run "tail -n10000 /var/log/kcarectl.log"
dump "/etc/kdump.conf"
dump "/etc/cron.d/kcare-cron"

CR_DIR="/var/cache/kcare/dumps/"
if [ -d "$CR_DIR" ]; then
    dump_crash_logs
    dump_kmsgs
	run "ls -lR $CR_DIR"
fi

if [ -e "/etc/kdump.conf" ]; then
  KDUMP_PATH=`grep ^path /etc/kdump.conf|cut -d' ' -f2`
  KDUMP_PATH=${KDUMP_PATH:-/var/crash}
  if [ -d "$KDUMP_PATH" ]; then
    run "ls -lR $KDUMP_PATH"
    # it only works correctly on RHEL based systems, should be
    # adjusted for Debian/Ubuntu
    for evt in $(ls "$KDUMP_PATH"); do
      dump "$KDUMP_PATH/$evt/vmcore-dmesg.txt"
    done
  fi
fi
run aa-status
run sestatus
run "cat /sys/kernel/debug/kprobes/list"
get_sysfs_info

run lsblk -f
run df -h

echo
echo "Uploading..."
echo -n "Key: "
if upload
then
echo
echo "Please, provide above mentioned key to KernelCare Support Team"
cleanup
else
echo
echo "There were some connection errors. Please, provide ${DEST} file to KernelCare Support Team"
fi
echo
