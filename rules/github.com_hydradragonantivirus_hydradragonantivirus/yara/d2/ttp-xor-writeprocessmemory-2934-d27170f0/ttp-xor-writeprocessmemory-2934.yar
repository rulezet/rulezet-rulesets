rule TTP_XOR_WriteProcessMemory_2934 {
  strings:
    $key_2934 = { 7e 46 [2] 4c 64 [2] 4a 51 [2] 64 51 [2] 5b 4d }

  condition:
    any of them
}