rule TTP_XOR_WriteProcessMemory_2852 {
  strings:
    $key_2852 = { 7f 20 [2] 4d 02 [2] 4b 37 [2] 65 37 [2] 5a 2b }

  condition:
    any of them
}