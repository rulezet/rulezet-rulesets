rule TTP_XOR_WriteProcessMemory_058e {
  strings:
    $key_058e = { 52 fc [2] 60 de [2] 66 eb [2] 48 eb [2] 77 f7 }

  condition:
    any of them
}