@load base/frameworks/cluster
@load base/frameworks/notice
@load policy/protocols/ssl/validate-certs

module Suppress_SSL_Notices;

export{
        option list_filename= "/usr/local/zeek/share/zeek/site/domains.list";
}

type notice_msg: enum { ANY , SELF_SIGNED , EXPIRED , LOCAL_ISSUER , SELF_SIGNED_IN_CHAIN };
type notice_network_direction: enum { ANY_DIRECTION, INBOUND , OUTBOUND , INTERNAL ,EXTERNAL };

const notice_msg_table: table[notice_msg] of string = {
        [Suppress_SSL_Notices::SELF_SIGNED] = "self signed certificate" ,
        [Suppress_SSL_Notices::EXPIRED] = "certificate has expired"   ,
        [Suppress_SSL_Notices::LOCAL_ISSUER] = "unable to get local issuer certificate",
        [Suppress_SSL_Notices::SELF_SIGNED_IN_CHAIN] = "self signed certificate in certificate chain"
};


type Idx: record {
        description: string;
};

type Val: record {
        domain: string;
        notice_msg_type: notice_msg;
        network_direction: notice_network_direction;
};

global exclude_domains_table: table[string] of Val &broker_allow_complex_type &backend=Broker::MEMORY;


event zeek_init(){
        @if (!Cluster::is_enabled() || (Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER))
                Input::add_table([$source=list_filename, $name="domains_list", $idx=Idx, $val=Val ,$destination=exclude_domains_table, $mode=Input::REREAD]);
        @endif
}

event Input::end_of_data(name: string, source: string) {

        @if (!Cluster::is_enabled() || (Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER))
                Reporter::info($msg="New Exclude Domain List Loaded. List Length: "+ cat(|exclude_domains_table|));
        @endif
}



function get_direction(src: addr ,dst: addr): notice_network_direction{

        local network_direction: notice_network_direction;
        local src_bool: bool = Site::is_local_addr(src);
        local dst_bool: bool = Site::is_local_addr(dst);

        if ( src_bool == T && dst_bool == F) 
                network_direction = Suppress_SSL_Notices::OUTBOUND;
        if ( src_bool == F && dst_bool == T) 
                network_direction = Suppress_SSL_Notices::INBOUND;
        if ( src_bool == T && dst_bool == T) 
                network_direction = Suppress_SSL_Notices::INTERNAL;
        if ( src_bool == F && dst_bool == F) 
                network_direction = Suppress_SSL_Notices::EXTERNAL;
        
        return network_direction;
}


hook Notice::policy(n: Notice::Info) &priority=5
{
       
       if  ( n?$note && n$note != SSL::Invalid_Server_Cert)
                return;

       if ( |exclude_domains_table| == 0)
                return;

       for (row in exclude_domains_table){
               local nm = exclude_domains_table[row]$notice_msg_type;
               if  (  nm == Suppress_SSL_Notices::ANY || notice_msg_table[nm] in n$msg ){
                        local d  = exclude_domains_table[row]$network_direction;
                        if ( d == Suppress_SSL_Notices::ANY_DIRECTION || d == get_direction(n$src,n$dst) ){

                                local p = exclude_domains_table[row]$domain;
                                
                                if ( p in "ANY_CERT" || p in n$sub){

                                        n$actions = Notice::ActionSet(Notice::ACTION_NONE);
                                        #Reporter::info("Exclude: "+n$sub);
                        
                                }
                        }

               }
        }

}
