event http_entity_data(c: connection, is_orig: bool, entity_length: count, data: string)
  {
  if ( /or.?1.?=.?1.?--/i in data )
    {
    local msg = fmt("SQLi attempt detected in BODY from %s to %s", c$id$orig_h, c$id$resp_h);
    NOTICE([$note=SQLi_Attempt, $msg=msg, $conn=c]);
    }
  }