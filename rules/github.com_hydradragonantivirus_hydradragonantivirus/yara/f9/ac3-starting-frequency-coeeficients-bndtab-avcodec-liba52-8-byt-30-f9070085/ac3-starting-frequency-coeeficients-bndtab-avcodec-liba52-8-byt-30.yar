rule AC3_starting_frequency_coeeficients_bndtab__avcodec___liba52___8_byt_30_ {
  strings:
    $a0 = { 15 16 17 18 19 1a 1b 1c 1f 22 25 28 2b 2e 31 37 3d 43 49 4f 55 61 6d 79 85 9d b5 cd e5 fd }

  condition:
    $a0
}