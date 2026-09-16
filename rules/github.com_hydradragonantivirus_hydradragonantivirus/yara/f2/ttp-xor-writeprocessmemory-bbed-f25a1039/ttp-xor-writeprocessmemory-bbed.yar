rule TTP_XOR_WriteProcessMemory_bbed {
  strings:
    $key_bbed = { ec 9f [2] de bd [2] d8 88 [2] f6 88 [2] c9 94 }

  condition:
    any of them
}