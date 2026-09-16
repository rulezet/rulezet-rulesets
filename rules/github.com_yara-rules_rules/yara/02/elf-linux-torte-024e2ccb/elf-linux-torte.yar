rule ELF_Linux_Torte : Linux ELF

{
    meta:
		author = "@mmorenog,@yararules"
		description = "Detects ELF Linux/Torte infection"
		ref = "http://blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html"
		hash1 = "1faf27f6b8e8a9cadb611f668a01cf73"
		hash2 = "cb0477445fef9c5f1a5b6689bbfb941e"

    strings:
        $s0 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.6)"
        $s1 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.7.6)"
        $s2 = "?sessd="
        $s3 = "&sessc="
        $s4 = "&sessk="
        $s5 = "3a08fe7b8c4da6ed09f21c3ef97efce2"
        $s6 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s7 = "_ZN11CThreadPool10getBatchesERSt6vectorISt4pairISsiESaIS2_EE"
        $s8 = "_ZNSs4_Rep10_M_destroyERKSaIcE@@GLIBCXX_3.4"
        $s9 = "_ZNSt6vectorImSaImEE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPmS1_EERKm"
        $s10 = "_ZNSt6vectorISt4pairISsiESaIS1_EE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPS1_S3_EERKS1_"
        $s11 = "_ZSt20__throw_out_of_rangePKc@@GLIBCXX_3.4"
        
        condition:
        is__elf and all of ($s*)
}