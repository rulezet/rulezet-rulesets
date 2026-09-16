rule TTP_XOR_WriteProcessMemory_d897 {
  strings:
    $key_d897 = { 8f e5 [2] bd c7 [2] bb f2 [2] 95 f2 [2] aa ee }

  condition:
    any of them
}