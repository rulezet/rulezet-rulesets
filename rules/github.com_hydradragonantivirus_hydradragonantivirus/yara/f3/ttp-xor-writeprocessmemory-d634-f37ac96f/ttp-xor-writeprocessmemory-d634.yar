rule TTP_XOR_WriteProcessMemory_d634 {
  strings:
    $key_d634 = { 81 46 [2] b3 64 [2] b5 51 [2] 9b 51 [2] a4 4d }

  condition:
    any of them
}