#[deriving(PartialEq,Show)]
pub enum IdentifierError {
	ReservedIdentifierError(i64),
	UnassignedIdentifierError(i64),
	PrivateUseIdentifierError(i64),
	UnknownIdentifierError(i64)
}