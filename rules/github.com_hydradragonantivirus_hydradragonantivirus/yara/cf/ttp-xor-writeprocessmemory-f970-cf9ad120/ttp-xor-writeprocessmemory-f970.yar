rule TTP_XOR_WriteProcessMemory_f970 {
  strings:
    $key_f970 = { ae 02 [2] 9c 20 [2] 9a 15 [2] b4 15 [2] 8b 09 }

  condition:
    any of them
}