rule TTP_XOR_WriteProcessMemory_f820 {
  strings:
    $key_f820 = { af 52 [2] 9d 70 [2] 9b 45 [2] b5 45 [2] 8a 59 }

  condition:
    any of them
}