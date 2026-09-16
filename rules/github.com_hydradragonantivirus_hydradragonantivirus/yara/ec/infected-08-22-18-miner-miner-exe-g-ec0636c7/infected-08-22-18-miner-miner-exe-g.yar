rule infected_08_22_18_miner_miner_exe_g {
  meta:
    description = "miner-exe - file g"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"

  strings:
    $s1  = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" fullword ascii
    $s2  = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" fullword ascii
    $s3  = "+ 1) - (size_t)(const void *)(__tzname[tp->tm_isdst]) == 1) && (__s2_len = __builtin_strlen (__tzname[tp->tm_isdst]), __s2_len " fullword ascii
    $s4  = "= (__s1[2] - ((__const unsigned char *) (__const char *) (__tzname[tp->tm_isdst]))[2]); if (__s2_len > 2 && __result == 0) __re" fullword ascii
    $s5  = "ize_t))) - 1)) & ~((2 * (sizeof(size_t))) - 1))) && ((old_top)->size & 0x1) && ((unsigned long)old_end & pagemask) == 0)" fullword ascii
    $s6  = "(((unsigned long)(((void*)((char*)(p) + 2*(sizeof(size_t))))) & ((2 * (sizeof(size_t))) - 1)) == 0)" fullword ascii
    $s7  = "((unsigned long)((void*)((char*)(brk) + 2*(sizeof(size_t)))) & ((2 * (sizeof(size_t))) - 1)) == 0" fullword ascii
    $s8  = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
    $s9  = "- ((__const unsigned char *) (__const char *) (__tzname[tp->tm_isdst]))[0]; if (__s2_len > 0 && __result == 0) { __result = (__" fullword ascii
    $s10 = "((size_t)((void*)((char*)(mm) + 2*(sizeof(size_t)))) & ((2 * (sizeof(size_t))) - 1)) == 0" fullword ascii
    $s11 = "Fake name process" fullword ascii
    $s12 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii
    $s13 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
    $s14 = "relocation processing: %s%s" fullword ascii
    $s15 = "ELF load command address/offset not properly aligned" fullword ascii
    $s16 = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
    $s17 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
    $s18 = "__pthread_mutex_lock" fullword ascii
    $s19 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
    $s20 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 2000KB and
      (8 of them)
    ) or (all of them)
}