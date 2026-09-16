rule TTP_XOR_WriteProcessMemory_dee8 {
  strings:
    $key_dee8 = { 89 9a [2] bb b8 [2] bd 8d [2] 93 8d [2] ac 91 }

  condition:
    any of them
}