rule TTP_XOR_WriteProcessMemory_f9ae {
  strings:
    $key_f9ae = { ae dc [2] 9c fe [2] 9a cb [2] b4 cb [2] 8b d7 }

  condition:
    any of them
}