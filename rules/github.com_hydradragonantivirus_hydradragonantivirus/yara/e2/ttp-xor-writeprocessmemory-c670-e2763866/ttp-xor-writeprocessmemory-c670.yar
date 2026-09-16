rule TTP_XOR_WriteProcessMemory_c670 {
  strings:
    $key_c670 = { 91 02 [2] a3 20 [2] a5 15 [2] 8b 15 [2] b4 09 }

  condition:
    any of them
}