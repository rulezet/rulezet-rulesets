rule TTP_XOR_WriteProcessMemory_bbff {
  strings:
    $key_bbff = { ec 8d [2] de af [2] d8 9a [2] f6 9a [2] c9 86 }

  condition:
    any of them
}