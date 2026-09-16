rule TTP_XOR_WriteProcessMemory_ab24 {
  strings:
    $key_ab24 = { fc 56 [2] ce 74 [2] c8 41 [2] e6 41 [2] d9 5d }

  condition:
    any of them
}