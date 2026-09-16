import "elf"
rule ttp_lib_pcap_elf_alt: ttp {
  meta:
    author = "stvemillertime"
    note   = "usually a pretty good idea to look for executables with pcap functionality, try to tune out some legit stuff"
    desc   = "elfs with pcap_ function strings, may indicate use of libpcap"
    ref    = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"      ref    = "427a0860365f15c1408708c2d6ed527e4e12ad917a1fa111d190c6601148a1eb"      ref    = "acd07de34cc15f49fd919dc18e695632a08a132fcfc4e9b6292e1a0d45e953e5"      ref    = "8a0a9740cf928b3bd1157a9044c6aced0dfeef3aa25e9ff9c93e113cbc1117ee"  
  strings:
    $a = "pcap_" nocase
    $b = "pcap_" xor(0x01-0xff)
    $c = "pcap_" base64 base64wide

  condition:
    elf.type == elf.ET_EXEC
            and #a + #b + #c > 1
}