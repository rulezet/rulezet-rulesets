rule Mimikatz_SampleSet_8: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    super_rule  = 1
    hash0       = "0a10fe0a341ac0b24347f183c83123cc"
    hash1       = "d7e16bc11cdfc0f781e87f5df4ae24a5"
    hash2       = "abdb41e32c447e703b03c9e307565ed3"
    score       = 40

  strings:
    $s0 = "?!?(?0?8?@?H?P?X?`?n?w?" fullword
    $s1 = "2\"2'2.24292@2F2K2R2X2]2d2j2o2v2|2" fullword
    $s2 = "7!7<7C7P7V7^7d7r7" fullword
    $s3 = "0#0)0=0E0K0[0c0i0" fullword
    $s4 = "878E8L8Y8`8f8l8r8" fullword
    $s5 = ":*:/:7:=:B:I:O:T:[:a:f:m:s:x:" fullword
    $s6 = "<'<4<9<D<K<Q<X<e<j<u<{<" fullword
    $s7 = "8&878?8M8R8]8d8q8~8" fullword
    $s8 = ";,;2;A;F;L;_;d;k;q;" fullword
    $s9 = "3%3+31373=3C3I3N3_3s3" fullword

  condition:
    all of them
}