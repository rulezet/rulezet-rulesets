rule TTP_XOR_WriteProcessMemory_baea {
  strings:
    $key_baea = { ed 98 [2] df ba [2] d9 8f [2] f7 8f [2] c8 93 }

  condition:
    any of them
}