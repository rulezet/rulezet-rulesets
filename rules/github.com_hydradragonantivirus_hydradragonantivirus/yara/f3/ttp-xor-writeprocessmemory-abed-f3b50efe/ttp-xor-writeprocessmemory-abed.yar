rule TTP_XOR_WriteProcessMemory_abed {
  strings:
    $key_abed = { fc 9f [2] ce bd [2] c8 88 [2] e6 88 [2] d9 94 }

  condition:
    any of them
}