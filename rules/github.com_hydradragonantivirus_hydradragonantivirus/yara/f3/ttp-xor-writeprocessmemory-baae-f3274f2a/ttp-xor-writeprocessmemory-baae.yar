rule TTP_XOR_WriteProcessMemory_baae {
  strings:
    $key_baae = { ed dc [2] df fe [2] d9 cb [2] f7 cb [2] c8 d7 }

  condition:
    any of them
}