cmd_/home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/tmp-install/include/linux/netfilter/ipset/.install := perl scripts/headers_install.pl /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/include/linux/netfilter/ipset /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/tmp-install/include/linux/netfilter/ipset arm ip_set.h ip_set_bitmap.h ip_set_hash.h ip_set_list.h; perl scripts/headers_install.pl /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/include/linux/netfilter/ipset /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/tmp-install/include/linux/netfilter/ipset arm ; perl scripts/headers_install.pl /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/include/generated/linux/netfilter/ipset /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/tmp-install/include/linux/netfilter/ipset arm ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/tmp-install/include/linux/netfilter/ipset/$$F; done; touch /home/sying/wucaiyuan_toolchain/v300/uclibc_gcc4.8_linaro_toolchain_optimized/linux-2012.09/tmp-install/include/linux/netfilter/ipset/.install
