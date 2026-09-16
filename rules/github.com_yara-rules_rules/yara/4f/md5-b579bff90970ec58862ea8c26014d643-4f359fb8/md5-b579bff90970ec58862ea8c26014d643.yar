rule md5_b579bff90970ec58862ea8c26014d643 {
    
    strings: $ = /<Files [^>]+.(jpg|png|gif)>\s*ForceType application\/x-httpd-php/
    condition: any of them
}