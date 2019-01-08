<?php namespace P0f;

define("P0F_QUERY_MAGIC", 0x50304601);
define("P0F_ADDR_IPV4", 0x04);      
define("P0F_ADDR_IPV6", 0x06);
class Client
{
    public static function get(string $socket, string $ip)
    {
        $q = [];
        $q['magic'] = P0F_QUERY_MAGIC;
        if(strpos($ip, ':') === false)
        {
            self::parse_addr4($ip, $q);
            $q['addr_type'] = P0F_ADDR_IPV4;
        }
        else
        {
            self::parse_addr6($ip, $q);
            $q['addr_type'] = P0F_ADDR_IPV6;
        }

        $socket = fsockopen("unix://" . $socket, -1);
        if(!is_resource($socket)) throw new \Exception("Can't connect to API socket.");
        function c($a){
            echo $a;
        }
        $p0f_api_query = pack("ICC16", $q['magic'], $q['addr_type'], $q['addr'][0],$q['addr'][1],$q['addr'][2],$q['addr'][3],$q['addr'][4]??null,$q['addr'][5]??null,$q['addr'][6]??null,$q['addr'][7]??null,$q['addr'][8]??null,$q['addr'][9]??null,$q['addr'][10]??null,$q['addr'][11]??null,$q['addr'][12]??null,$q['addr'][13]??null,$q['addr'][14]??null,$q['addr'][15]??null);
        if(! fwrite($socket, $p0f_api_query)) throw new \Exception("Short write to API socket.");
        $res = fread($socket, 2000);
        $res = unpack("Imagic/Istatus/Ifirst_seen/Ilast_seen/Itotal_conn/Iuptime_min/Iup_mod_days/Ilast_nat/Ilast_chg/sdistance/Cbad_sw/Cos_match_q/a32os_name/a32os_flavor/a32http_name/a32http_flavor/Slink_mtu/a32link_type/a32language",$res);
        fclose($socket);
        array_walk($res, function(&$value){
            
            $value = trim($value);
        });
        $res['query'] = $ip;
        return json_encode($res);
    }

    public static function parse_addr4(string $ip, array &$q)
    {
        if(sscanf($ip, "%u.%u.%u.%u", $a1, $a2, $a3, $a4) != 4) throw new \Exception("Malformed IPv4 address.");
        if($a1 > 255 || $a2 > 255 ||$a3 > 255 || $a4 > 255)
        {
            throw new \Exception("Malformed IPv4 address.");
        }
        $q['addr'][0] = $a1;
        $q['addr'][1] = $a2;
        $q['addr'][2] = $a3;
        $q['addr'][3] = $a4;
    }

    public static function parse_addr6(string $ip, array &$q)
    {
    }
}
