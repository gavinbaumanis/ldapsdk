/*
 * Copyright 2026 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2026 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2026 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util.ssl;



import java.io.Serializable;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.X509Certificate;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an X.509 trust manager implementation that can be used to
 * verify signatures in a certificate chain.  It will verify that self-signed
 * certificates have valid signatures, and that if multiple certificates are
 * provided, they form a valid chain in which each subsequent certificate has
 * signed the previous certificate.  This implementation is somewhat lenient
 * when it comes to certificate order:  the first certificate must be the
 * end-entity certificate, but subsequent certificates can appear in any order.
 * Further, if the chain includes duplicate certificates, then the duplicates
 * will be ignored so that only one instance of each certificate will be
 * examined.
 * <BR><BR>
 * Note that this trust manager should not be used on its own, since it only
 * validates the certificate chain that was actually presented by the peer.
 * If the presented chain is incomplete (which is acceptable if there is reason
 * to expect that the peer can complete the chain using its own set of trusted
 * issuers), then this trust manager will not attempt to verify that the last
 * certificate presented by the peer was actually signed by one of those
 * trusted issuers.  And even in the case where the full chain is presented,
 * this trust manager only attempts to verify that each subsequent certificate
 * is the one used to sign the previous one, and does not attempt to make any
 * determination about whether any of the end-entity or issuer certificates are
 * trustworthy.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
  public final class VerifyChainSignaturesTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final java.security.cert.X509Certificate[]
       NO_CERTIFICATES = new java.security.cert.X509Certificate[0];



  /**
   * The singleton instance of this trust manager.
   */
  @NotNull private static final VerifyChainSignaturesTrustManager INSTANCE =
       new VerifyChainSignaturesTrustManager();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2712657207894506440L;



  /**
   * Creates a new instance of this trust manager.
   */
  private VerifyChainSignaturesTrustManager()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this issuer chain trust manager.
   *
   * @return  A singleton instance of this issuer chain trust manager.
   */
  @NotNull()
  public static VerifyChainSignaturesTrustManager getInstance()
  {
    return INSTANCE;
  }



  /**
   * Checks to determine whether the provided client certificate chain should be
   * trusted.
   *
   * @param  chain     The client certificate chain for which to make the
   *                   determination.
   * @param  authType  The authentication type based on the client certificate.
   *
   * @throws  CertificateException  If the provided client certificate chain
   *                                should not be trusted.
   */
  @Override()
  public void checkClientTrusted(
                   @NotNull final java.security.cert.X509Certificate[] chain,
                   @NotNull final String authType)
         throws CertificateException
  {
    validateIssuerChain(chain);
  }



  /**
   * Checks to determine whether the provided server certificate chain should be
   * trusted.
   *
   * @param  chain     The server certificate chain for which to make the
   *                   determination.
   * @param  authType  The key exchange algorithm used.
   *
   * @throws  CertificateException  If the provided server certificate chain
   *                                should not be trusted.
   */
  @Override()
  public void checkServerTrusted(
                   @NotNull final java.security.cert.X509Certificate[] chain,
                   @NotNull final String authType)
         throws CertificateException
  {
    validateIssuerChain(chain);
  }



  /**
   * Ensures that the certificates in the provided array represent a valid chain
   * of issuer certificates.
   *
   * @param  chain  The certificate chain to validate.
   *
   * @throws  CertificateException  If the provided array does not represent a
   *                                valid chain of issuer certificates.
   */
  private void validateIssuerChain(
                    @NotNull final java.security.cert.X509Certificate[] chain)
           throws CertificateException
  {
    // If the provided chain is null or empty, then we will not accept the
    // certificate chain.
    if ((chain == null) || (chain.length < 1))
    {
      throw new CertificateException(
           ERR_VERIFY_CHAIN_SIGNATURES_TRUST_NO_CHAIN.get());
    }


    // Convert the certificates in the provided chain to use the LDAP SDK's
    // representation of the certificates.  The first certificate is one that
    // we will treat as the end-entity certificate, and the others will be
    // treated as potential issuers.  Technically, they should be in the right
    // order, but we'll be lenient in that regard.
    final X509Certificate endEntityCertificate = parseCertificate(
         chain[0].getEncoded(),
         String.valueOf(chain[0].getSubjectX500Principal()),  0);
    final Set<X509Certificate> issuerCertificates = new HashSet<>();
    for (int i=1; i < chain.length; i++)
    {
      issuerCertificates.add(parseCertificate(chain[i].getEncoded(),
         String.valueOf(chain[i].getSubjectX500Principal()),  i));
    }


    // If the end-entity certificate happened to be included multiple times in
    // the chain, then remove it from the set of issuer certificates.
    issuerCertificates.remove(endEntityCertificate);


    // If the end-entity certificate is self-signed, then validate its
    // signature.  Also, make sure that the chain didn't include any other
    // certificates, since they wouldn't be related to the chain.
    if (endEntityCertificate.isSelfSigned())
    {
        try
        {
          endEntityCertificate.verifySignature(endEntityCertificate);
        }
        catch (final CertException e)
        {
          Debug.debugException(e);
          throw new CertificateException(e.getMessage(), e);
        }

        if (! issuerCertificates.isEmpty())
        {
          throw new CertificateException(
               ERR_VERIFY_CHAIN_SIGNATURES_TRUST_UNRELATED_CERTS.get(
                    String.valueOf(endEntityCertificate.getSubjectDN())));
        }

        return;
    }


    // If the chain only has a single certificate, then we don't need to
    // perform any other validation.  This can happen if the end-entity
    // certificate is self-signed (which we've already accounted for), or if
    // we're supposed to be able to complete the chain from a known set of
    // trusted issuers (which is outside the scope of this trust manager).
    if (issuerCertificates.isEmpty())
    {
      return;
    }


    // At this point, we know that the end-entity certificate isn't self-signed,
    // and that at least one more certificate was included in the presented
    // chain.  Make sure that we can form a chain from the presented
    // certificates.
    X509Certificate previousCertificate = endEntityCertificate;
    while (! issuerCertificates.isEmpty())
    {
      // Try to find the issuer of the certificate we most recently examined.
      boolean foundIssuer = false;
      final Iterator<X509Certificate> iterator = issuerCertificates.iterator();
      while (iterator.hasNext())
      {
        final X509Certificate potentialIssuer = iterator.next();
        if (potentialIssuer.isIssuerFor(previousCertificate))
        {
          try
          {
            previousCertificate.verifySignature(potentialIssuer);
            previousCertificate = potentialIssuer;
            iterator.remove();
            foundIssuer = true;
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertificateException(
                 ERR_VERIFY_CHAIN_SIGNATURES_ISSUER_SIGNATURE_INVALID.get(
                      String.valueOf(previousCertificate.getSubjectDN()),
                      String.valueOf(potentialIssuer.getSubjectDN())),
                 e);
          }
        }
      }


      // If we didn't find the issuer in the set of certificates, then that's an
      // error.
      if (! foundIssuer)
      {
        throw new CertificateException(
             ERR_VERIFY_CHAIN_SIGNATURES_COULD_NOT_FIND_ISSUER.get(
                  String.valueOf(previousCertificate.getSubjectDN())));
      }


      // If the issuer certificate is self-signed, then make sure that its
      // signature is valid, and also that there aren't any other remaining
      // certificates.
      if (previousCertificate.isSelfSigned())
      {
        try
        {
          previousCertificate.verifySignature(previousCertificate);
        }
        catch (final CertException e)
        {
          Debug.debugException(e);
          throw new CertificateException(e.getMessage(), e);
        }

        if (! issuerCertificates.isEmpty())
        {
          throw new CertificateException(
               ERR_VERIFY_CHAIN_SIGNATURES_TRUST_UNRELATED_CERTS.get(
                    String.valueOf(endEntityCertificate.getSubjectDN())));
        }

        return;
      }
    }


    // If we've gotten here, then it means that we've gone through all of the
    // issuers included in the chain, and that the last certificate we found
    // wasn't self-signed.  This just means that the peer didn't provide the
    // complete certificate chain, and expects us to complete it from a set of
    // trusted issuers.  That's outside the scope of this trust manager, so
    // we're fine exiting without throwing an exception.
  }



  /**
   * Parses the contents of the provided byte array as an X.509 certificate.
   *
   * @param  certBytes      The byte array containing the certificate data to
   *                        parse.
   * @param  certSubjectDN  The string representation of the expected subject DN
   *                        for the certificate.
   * @param  index          The index of the certificate in the chain.
   *
   * @return  The parsed certificate.
   *
   * @throws  CertificateException  If the contents of the provided byte array
   *                                can't be parsed as an X.509 certificate.
   */
  @NotNull()
  static X509Certificate parseCertificate(
              @NotNull final byte[] certBytes,
              @NotNull final String certSubjectDN,
              final int index)
         throws CertificateException
  {
      try
      {
        return new X509Certificate(certBytes);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new CertificateException(
             ERR_VERIFY_CHAIN_SIGNATURES_TRUST_CANNOT_PARSE_CERT.get(
                  certSubjectDN, index, StaticUtils.getExceptionMessage(e)));
      }
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.  This
   * will always return an empty array.
   *
   * @return  The accepted issuer certificates for this trust manager.
   */
  @Override()
  @NotNull()
  public java.security.cert.X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
