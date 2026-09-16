rule TTP_XOR_WriteProcessMemory_dee0 {
  strings:
    $key_dee0 = { 89 92 [2] bb b0 [2] bd 85 [2] 93 85 [2] ac 99 }

  condition:
    any of them
}