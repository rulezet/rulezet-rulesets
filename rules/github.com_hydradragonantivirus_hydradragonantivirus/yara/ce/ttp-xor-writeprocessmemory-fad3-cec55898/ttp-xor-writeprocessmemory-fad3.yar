rule TTP_XOR_WriteProcessMemory_fad3 {
  strings:
    $key_fad3 = { ad a1 [2] 9f 83 [2] 99 b6 [2] b7 b6 [2] 88 aa }

  condition:
    any of them
}