require 'digest/sha1'

class User
  include DataMapper::Resource

  attr_accessor :password, :password_confirmation

  property :id, Serial, :auto_validation => true, :lazy => false
  property :email, String, :nullable => false, :length => (5..40), :unique => true, :format => :email_address, :auto_validation => true, :lazy => false
  property :hashed_password, String, :auto_validation => true, :lazy => false
  property :salt, String, :nullable => false, :auto_validation => true, :lazy => false
  property :created_at, Time, :auto_validation => true, :lazy => false
  property :permission_level, Integer, :default => 1, :auto_validation => true, :lazy => false

  validates_present :password_confirmation, :unless => Proc.new { |t| t.hashed_password }
  validates_present :password, :unless => Proc.new { |t| t.hashed_password }
  validates_is_confirmed :password

  def self.authenticate(email, pass)
    current_user = first(:email => email)
    return nil if current_user.nil?
    return current_user if User.encrypt(pass, current_user.salt) == current_user.hashed_password
    nil
  end  

  def password=(pass)
    @password = pass
    self.salt = User.random_string(10) if !self.salt
    self.hashed_password = User.encrypt(@password, self.salt)
  end

  def admin?
    self.permission_level == -1 || self.id == 1
  end
  protected

  def self.encrypt(pass, salt)
    ::Digest::SHA1.hexdigest(pass+salt)
  end

  def self.random_string(len)
    #generate a random password consisting of strings and digits
    chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
    newpass = ""
    1.upto(len) { |i| newpass << chars[rand(chars.size-1)] }
    return newpass
  end

  def method_missing(m, *args)
    return false
  end
end
