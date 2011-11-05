<?php

/**
 * @see Zend_Auth_Adapter_Interface
 */
require_once 'Zend/Auth/Adapter/Interface.php';

/**
 * @category   Shanty
 * @package    Shanty_Paginator
 * @copyright  Shanty Tech Pty Ltd
 * @license    New BSD License
 * @author     Acido69
 */
class Shanty_Auth_Adapter_Mongo  implements Zend_Auth_Adapter_Interface
{
    /**
     * $_document - Document of User
     *
     * @var Shanty_Mongo_Document
     */
    protected $_document = null;


    /**
     * $_identityName - Property name of identity
     *
     * @var string
     */
    protected $_identityName = null;

    /**
     * $_credentialName - Property name of credential
     *
     * @var string
     */
    protected $_credentialName = null;
    
    /**
     * $_credential - Credential value
     *
     * @var string
     */
    protected $_credential = null;

    /**
     * $_identity - Identity value
     *
     * @var string
     */
    protected $_identity = null;

    /**
     * $_authenticateResultInfo
     *
     * @var array
     */
    protected $_authenticateResultInfo = null;




    public function  __construct(Shanty_Mongo_Document $document, $identityName = null, $credentialName = null ) 
    {
        $this->_document = $document;
        
        if(null !== $document){
            $this->_identityName = $identityName;
        }
        if(null !== $document){
            $this->_credentialName = $credentialName;
        }
    }

    /**
     * setIdentityName() - set name  of property to compare identity
     *
     * @param  string $identityName
     * @return Shanty_Auth_Adapter_Mongo Provides a fluent interface
     */
    public function setIdentityName($indentityName)
    {
        $this->_identityName = $indentityName;
        return $this;
    }

    /**
     * setCredentialName() - set name  of property to compare crendential
     *
     * @param  string $credentialName
     * @return Shanty_Auth_Adapter_Mongo Provides a fluent interface
     */
    public function setCredentialName($credentialName)
    {
        $this->_credentialName = $credentialName;
        return $this;
    }
    
    /**
     * setIdentity() - set the value to be used as the identity
     *
     * @param  string $value
     * @return Shanty_Auth_Adapter_Mongo Provides a fluent interface
     */
    public function setIdentity($value)
    {
        $this->_identity = $value;
        return $this;
    }

    /**
     * setCredential() - set the credential value to be used
     *
     * @param  string $credential
     * @return Shanty_Auth_Adapter_Mongo Provides a fluent interface
     */
    public function setCredential($credential)
    {
        $this->_credential = $credential;
        return $this;
    }
    
    /**
     * authenticate() - defined by Zend_Auth_Adapter_Interface.  This method is called to
     * attempt an authentication.  Previous to this call, this adapter would have already
     * been configured with all necessary information to successfully connect to a database
     * table and attempt to find a record matching the provided identity.
     *
     * @throws Zend_Auth_Adapter_Exception if answering the authentication query is impossible
     * @return Zend_Auth_Result
     */
    public function authenticate()
    {
        $this->_authenticateSetup();

        //$dbSelect = $this->_authenticateCreateSelect();
        $resultIdentities = $this->_authenticateQuerySelect();
        
        $authResult = $this->_authenticateValidateResultSet($resultIdentities) instanceof Zend_Auth_Result;

        return $authResult;
    }

    /**
     * _authenticateSetup() - This method abstracts the steps involved with
     * making sure that this adapter was indeed setup properly with all
     * required pieces of information.
     *
     * @throws Zend_Auth_Adapter_Exception - in the event that setup was not done properly
     * @return true
     */
    protected function _authenticateSetup()
    {
        $exception = null;

        if ($this->_identityName == '') {
            $exception = 'Name  of property to compare identity must be supplied for the Shanty_Auth_Adapter_Mongo adapter.';
        } elseif ($this->_credentialName == '') {
            $exception = 'Name  of property to compare credential must be supplied for the Shanty_Auth_Adapter_Mongo adapter.';
        } elseif ($this->_identity == '') {
            $exception = 'A value for the identity was not provided prior to authentication Shanty_Auth_Adapter_Mongo.';
        } elseif ($this->_credential === null) {
            $exception = 'A credential value was not provided prior to authentication with Shanty_Auth_Adapter_Mongo.';
        }

        if (null !== $exception) {
            /**
             * @see Zend_Auth_Adapter_Exception
             */
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception($exception);
        }

        $this->_authenticateResultInfo = array(
            'code'     => Zend_Auth_Result::FAILURE,
            'identity' => $this->_identity,
            'messages' => array()
            );

        return true;
    }

    /**
     * _authenticateQuerySelect() - Run query in Shanty_Mongo_Document instance
     *
     * @return Shanty_Mongo_Iterator_Cursor
     */
    protected function _authenticateQuerySelect()
    {
        //
        $resultIdentities = $this->_document->all(array(
            $this->_credentialName => $this->_credential
            ,$this->_identityName => $this->_identity
        ));

        return $resultIdentities;

    }

    /**
     * _authenticateValidateResultSet() - This method attempts to make
     * certain that only one record was returned in the resultset
     *
     * @param array $resultIdentities
     * @return true|Zend_Auth_Result
     */
    protected function _authenticateValidateResultSet($resultIdentities)
    {

        if(NULL === $resultIdentities || $resultIdentities->count()=== 0 ){
            $this->_authenticateResultInfo['code']          = Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND;
            $this->_authenticateResultInfo['messages'][]    = 'A record with the supplied identity could not be found.';
            return $this->_authenticateCreateAuthResult();
        }else if( $resultIdentities->count()>1 ){
            $this->_authenticateResultInfo['code']          = Zend_Auth_Result::FAILURE_IDENTITY_AMBIGUOUS;
            $this->_authenticateResultInfo['messages'][]    = 'More than one record matches the supplied identity.';
            return $this->_authenticateCreateAuthResult();
        }
        $resultIdentities->next();
        $this->_authenticateResultInfo['code']          = Zend_Auth_Result::SUCCESS;
        $this->_authenticateResultInfo['identity']      = $resultIdentities->current();
        $this->_authenticateResultInfo['messages'][]    = 'Authentication successful.';
        return $this->_authenticateCreateAuthResult();
    }

    /**
     * _authenticateCreateAuthResult() - Creates a Zend_Auth_Result object from
     * the information that has been collected during the authenticate() attempt.
     *
     * @return Zend_Auth_Result
     */
    protected function _authenticateCreateAuthResult()
    {
        return new Zend_Auth_Result(
            $this->_authenticateResultInfo['code'],
            $this->_authenticateResultInfo['identity'],
            $this->_authenticateResultInfo['messages']
            );
    }
}

?>
