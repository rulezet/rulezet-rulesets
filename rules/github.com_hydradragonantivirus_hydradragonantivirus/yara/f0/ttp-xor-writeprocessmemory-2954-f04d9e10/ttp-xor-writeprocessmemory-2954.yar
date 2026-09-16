rule TTP_XOR_WriteProcessMemory_2954 {
  strings:
    $key_2954 = { 7e 26 [2] 4c 04 [2] 4a 31 [2] 64 31 [2] 5b 2d }

  condition:
    any of them
}