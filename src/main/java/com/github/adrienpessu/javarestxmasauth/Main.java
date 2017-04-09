package com.github.adrienpessu.javarestxmasauth;

import com.github.adrienpessu.javarestxmasauth.api.Authentication;
import com.github.adrienpessu.javarestxmasauth.filter.CORSFilter;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.wildfly.swarm.Swarm;
import org.wildfly.swarm.jaxrs.JAXRSArchive;
import org.wildfly.swarm.spi.api.SwarmProperties;

/**
 * Created by adrien on 04/02/2017.
 */
public class Main {

    public static void main(String... args) throws Exception {


        Swarm swarm = new Swarm();

        JAXRSArchive deployment = ShrinkWrap.create(JAXRSArchive.class);
        deployment.addClass(Authentication.class);
        deployment.addResource( CORSFilter.class );
        deployment.addAllDependencies();
        swarm.start().deploy(deployment);

    }
}