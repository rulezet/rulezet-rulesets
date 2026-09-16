rule TTP_XOR_WriteProcessMemory_4099 {
  strings:
    $key_4099 = { 17 eb [2] 25 c9 [2] 23 fc [2] 0d fc [2] 32 e0 }

  condition:
    any of them
}