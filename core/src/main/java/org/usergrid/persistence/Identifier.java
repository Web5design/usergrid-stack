/*******************************************************************************
 * Copyright 2012 Apigee Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.usergrid.persistence;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.usergrid.utils.UUIDUtils;


public class Identifier implements Serializable {

    public enum Type {
        UUID, NAME, EMAIL
    }


    Type type;
    Object value;

    static Pattern emailRegEx = Pattern.compile( "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}" );
    static Pattern nameRegEx = Pattern.compile( "[a-zA-Z0-9_\\-./]*" );


    private Identifier( Type type, Object value ) {
        this.type = type;
        this.value = value;
    }


    public static Identifier from( Object obj ) {
        if ( obj == null ) {
            return null;
        }
        if ( obj instanceof UUID ) {
            return new Identifier( Type.UUID, obj );
        }
        if ( obj instanceof String ) {
            UUID uuid = UUIDUtils.tryGetUUID( ( String ) obj );
            if ( uuid != null ) {
                return new Identifier( Type.UUID, uuid );
            }
            Matcher m = emailRegEx.matcher( ( String ) obj );
            if ( m.matches() ) {
                return new Identifier( Type.EMAIL, ( ( String ) obj ).toLowerCase() );
            }
            m = nameRegEx.matcher( ( String ) obj );
            if ( m.matches() ) {
                return new Identifier( Type.NAME, ( ( String ) obj ).toLowerCase() );
            }
        }
        return null;
    }


    public static Identifier fromUUID( UUID uuid ) {
        if ( uuid == null ) {
            return null;
        }
        return new Identifier( Type.UUID, uuid );
    }


    public static Identifier fromName( String name ) {
        if ( name == null ) {
            return null;
        }
        return new Identifier( Type.NAME, name );
    }


    public static Identifier fromEmail( String email ) {
        if ( email == null ) {
            return null;
        }
        return new Identifier( Type.EMAIL, email );
    }


    @JsonIgnore
    public UUID getUUID() {
        if ( type != Type.UUID ) {
            return null;
        }
        return ( UUID ) value;
    }


    @JsonIgnore
    public boolean isUUID() {
        return type == Type.UUID;
    }


    @JsonIgnore
    public String getEmail() {
        if ( type != Type.EMAIL ) {
            return null;
        }
        return ( String ) value;
    }


    @JsonIgnore
    public boolean isEmail() {
        return type == Type.EMAIL;
    }


    @JsonIgnore
    public String getName() {
        if ( type != Type.NAME ) {
            return null;
        }
        return ( String ) value;
    }


    @JsonIgnore
    public boolean isName() {
        return type == Type.NAME;
    }


    public Type getType() {
        return type;
    }


    @Override
    public String toString() {
        return value != null ? value.toString() : null;
    }


    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ( ( type == null ) ? 0 : type.hashCode() );
        result = prime * result + ( ( value == null ) ? 0 : value.hashCode() );
        return result;
    }


    @Override
    public boolean equals( Object obj ) {
        if ( this == obj ) {
            return true;
        }
        if ( obj == null ) {
            return false;
        }
        if ( getClass() != obj.getClass() ) {
            return false;
        }
        Identifier other = ( Identifier ) obj;
        if ( type != other.type ) {
            return false;
        }
        if ( value == null ) {
            if ( other.value != null ) {
                return false;
            }
        }
        else if ( !value.equals( other.value ) ) {
            return false;
        }
        return true;
    }


    public static List<Identifier> fromList( List<String> l ) {
        List<Identifier> identifiers = null;
        if ( ( l != null ) && ( l.size() > 0 ) ) {
            for ( String s : l ) {
                Identifier identifier = Identifier.from( s );
                if ( identifier != null ) {
                    if ( identifiers == null ) {
                        identifiers = new ArrayList<Identifier>();
                    }
                    identifiers.add( identifier );
                }
            }
        }
        return identifiers;
    }


    // for serialization
    public Identifier() { }


    // for serialization
    public Object getValue() {
        return value;
    }


    // for serialization
    public void setValue( Object value ) {
        if ( isUUID() && value instanceof String ) {
            value = UUID.fromString( ( String ) value );
        }
        this.value = value;
    }
}
