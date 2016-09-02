/*
 * Copyright (c) 2016, Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * IOTAUTH_COPYRIGHT_VERSION_1
 */

package org.iot.auth.db.bean;

import org.iot.auth.db.SymmetricKeyCryptoSpec;
import org.iot.auth.server.CommunicationTargetType;
import org.iot.auth.util.DateHelper;
import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Communication Policy Table schema definition.  <br/>
 * It is not a formal BEAN but it is inspired by the concept.  <br/>
 * This class will store and process the data used to define the communication policy. <br/>
 * The communication policy is stored on a sqlite database.
 *
 * @author Salomon Lee
 */
public class CommunicationPolicyTable {
    public static final String T_COMMUNICATION_POLICY = "communication_policy";

    public enum c {
        RequestingGroup,
        TargetType,
        Target,
        CipherAlgorithm,
        HashAlgorithm,
        AbsoluteValidity,
        RelativeValidity
    }

    private String reqGroup;
    private CommunicationTargetType targetType;
    private String targetTypeVal;
    private String target;
    private long absValidity;
    private String absValidityStr;
    private long relValidity;
    private String relValidityStr;
    private String hashAlgo;
    private String cipherAlgo;

    private SymmetricKeyCryptoSpec cryptoSpec;

    /**
     * Gets the requesting group type
     * @return the requested group
     */
    public String getReqGroup() {
        return reqGroup;
    }

    /**
     * Sets the value for requesting group
     * @param reqGroup
     */
    public void setReqGroup(String reqGroup) {
        this.reqGroup = reqGroup;
    }

    /**
     * Gets the communication target type. <br/>
     * For more information {@link CommunicationTargetType}
     * @return the CommunicationTargetType
     */
    public CommunicationTargetType getTargetType() {
        return targetType;
    }

    /**
     * Sets the value for the communication target type.<br/>
     * For more information {@link CommunicationTargetType}
     * @param targetType
     */
    public void setTargetType(CommunicationTargetType targetType) {
        this.targetType = targetType;
    }

    /**
     * Gets the target to communicate
     * @return target
     */
    public String getTarget() {
        return target;
    }

    /**
     * Sets the target to communicate
     * @param target
     */
    public void setTarget(String target) {
        this.target = target;
    }

    /**
     * Gets the specification of the key used for the cryptography algorithm, it's hash algorithm and key length.<br/>
     * For more information see {@link SymmetricKeyCryptoSpec}
     * @return
     */
    public SymmetricKeyCryptoSpec getCryptoSpec() {
        return cryptoSpec;
    }


    public void setCryptoSpec(String cipherAlgo, String hashAlgo) {
        this.cipherAlgo = cipherAlgo;
        this.hashAlgo = hashAlgo;
        this.cryptoSpec = SymmetricKeyCryptoSpec.fromJSSpec(cipherAlgo, hashAlgo);
    }

    public long getAbsValidity() {
        return absValidity;
    }

    public void setAbsValidity(long absValidity) {
        this.absValidity = absValidity;
    }

    public long getRelValidity() {
        return relValidity;
    }

    public void setRelValidity(long relValidity) {
        this.relValidity = relValidity;
    }

    public String getHashAlgo() {
        return hashAlgo;
    }

    public void setHashAlgo(String hashAlgo) {
        this.hashAlgo = hashAlgo;
    }

    public String getCipherAlgo() {
        return cipherAlgo;
    }

    public void setCipherAlgo(String cipherAlgo) {
        this.cipherAlgo = cipherAlgo;
    }

    public void setCryptoSpec(SymmetricKeyCryptoSpec cryptoSpec) {
        this.cryptoSpec = cryptoSpec;
    }

    public String getTargetTypeVal() {
        return targetTypeVal;
    }

    public void setTargetTypeVal(String targetTypeVal) {
        this.targetTypeVal = targetTypeVal;
    }

    public String toString() {
        /*return "RequestingGroup: " + reqGroup + "\tTargetType: " + targetType + "\tTarget: " + target +
                "\t" + cryptoSpec.toString() +
                "\tAbsValidity: " + absValidity + "\tRelValidity: " + relValidity;*/
        return toJSONObject().toJSONString();
    }

    public String getAbsValidityStr() {
        return absValidityStr;
    }

    public void setAbsValidityStr(String absValidityStr) {
        this.absValidityStr = absValidityStr;
    }

    public String getRelValidityStr() {
        return relValidityStr;
    }

    public void setRelValidityStr(String relValidityStr) {
        this.relValidityStr = relValidityStr;
    }

    public JSONObject toJSONObject(){
        JSONObject object = new JSONObject();
        object.put(c.RequestingGroup.name(),getReqGroup());
        object.put(c.TargetType.name(),getTargetTypeVal());
        object.put(c.Target.name(),getTarget());
        object.put(c.AbsoluteValidity.name(), getAbsValidity());
        object.put(c.RelativeValidity.name(), getRelValidity());
        return object;
    }

    public static CommunicationPolicyTable createRecord(ResultSet r) throws SQLException {
        CommunicationPolicyTable policy = new CommunicationPolicyTable();
        policy.setReqGroup(r.getString(c.RequestingGroup.name()));
        policy.setTargetTypeVal(r.getString(c.TargetType.name()));
        policy.setTargetType(CommunicationTargetType.fromStringValue(r.getString(c.TargetType.name())));
        policy.setTarget(r.getString(c.Target.name()));
        policy.setCipherAlgo(r.getString(c.CipherAlgorithm.name()));
        policy.setHashAlgo(r.getString(c.HashAlgorithm.name()));
        policy.setCryptoSpec(policy.getCipherAlgo(),policy.getHashAlgo());
        policy.setAbsValidity(DateHelper.parseTimePeriod(r.getString(c.AbsoluteValidity.name())));
        policy.setRelValidity(DateHelper.parseTimePeriod(r.getString(c.RelativeValidity.name())));
        return policy;
    }

}